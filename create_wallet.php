<?php 
use kornrunner\Keccak;
use BitWasp\Bitcoin\Key\Factory\PrivateKeyFactory;
use BitWasp\Bitcoin\Crypto\Random\Random;
use BitWasp\Buffertools\Buffer;
use BitWasp\Bitcoin\Base58;

include_once "vendor/autoload.php";

$errmsg = ""; // Initialize $errmsg to avoid undefined variable warning

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    try {
        $privKeyFactory = new PrivateKeyFactory();

        // Check if the 'input' is empty or a valid hex string
        if (!isset($_POST['input']) || ctype_xdigit($_POST['input'])) {
            if (empty($_POST['input'])) { 
                // Generate a random private key if no input is provided
                $rbg = new Random();
                $privateKey = $privKeyFactory->generateUncompressed($rbg);
            } else {
                // Generate private key from provided hex input
                $privateKey = $privKeyFactory->fromHexUncompressed($_POST['input']);
            }

            $publicKey = $privateKey->getPublicKey();
            $publicKeyHex = substr($publicKey->getHex(), 2);

            $hash = Keccak::hash(hex2bin($publicKeyHex), 256);
            $hash = "41" . substr($hash, -40);

            $bf = Buffer::hex($hash);

            $tronAddress = Base58::encodeCheck($bf);
        } else {
            $errmsg = "Invalid input! Please enter a valid hexadecimal private key.";
        }
    } catch (Exception $e) {
        $errmsg = "Problem found. " . $e->getMessage();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Generate TRON Address</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <?php if ($errmsg): ?>
            <div class="alert alert-danger">
                <strong>Error!</strong> <?php echo $errmsg; ?>
            </div>
        <?php elseif ($_SERVER['REQUEST_METHOD'] == 'POST'): ?>
            <div class="table-responsive">
                <table class="table table-bordered">
                    <tr><th>Base58 Address</th><td><?php echo $tronAddress; ?></td></tr>
                    <tr><th>Hex Address</th><td><?php echo $bf->getHex(); ?></td></tr>
                    <tr><th>Private Key (Hex)</th><td><?php echo $privateKey->getHex(); ?></td></tr>
                    <tr><th>Public Key (Hex)</th><td><?php echo $publicKey->getHex(); ?></td></tr>
                </table>
            </div>
        <?php endif; ?>

        <form action="" method="post">
            <div class="form-group">
                <label for="input">Private Key (Hex):</label>
                <input class="form-control" type="text" name="input" id="input" value="<?php echo isset($_POST['input']) ? htmlspecialchars($_POST['input']) : ''; ?>">
                <small class="form-text text-muted">Leave empty to generate a random private key.</small>
            </div>
            <button type="submit" class="btn btn-success btn-block">Generate Address</button>
        </form>
    </div>
</body>
</html>
