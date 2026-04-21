<?php
echo "auto_prepend_file berjalan!";
echo "<br>Monitoring path: " . (@include_once '/home/chiacundippal/monitoring/autoload.php' ? 'SUCCESS' : 'FAILED');
?>
