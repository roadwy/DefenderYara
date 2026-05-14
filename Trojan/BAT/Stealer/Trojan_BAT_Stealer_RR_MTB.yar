
rule Trojan_BAT_Stealer_RR_MTB{
	meta:
		description = "Trojan:BAT/Stealer.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 69 70 20 3d 20 22 31 39 32 2e 31 36 38 2e 38 2e 31 22 } //1 $ip = "192.168.8.1"
		$a_01_1 = {24 70 61 79 6c 6f 61 64 20 3d 20 22 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 60 72 60 6e 48 6f 73 74 3a 20 24 69 70 60 72 60 6e 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 63 6c 6f 73 65 60 72 60 6e 60 72 60 6e 22 } //1 $payload = "GET / HTTP/1.1`r`nHost: $ip`r`nConnection: close`r`n`r`n"
		$a_01_2 = {24 63 6c 69 65 6e 74 20 3d 20 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73 2e 54 63 70 43 6c 69 65 6e 74 } //1 $client = New-Object System.Net.Sockets.TcpClient
		$a_01_3 = {24 62 79 74 65 73 20 3d 20 5b 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 41 53 43 49 49 2e 47 65 74 42 79 74 65 73 28 24 70 61 79 6c 6f 61 64 29 } //1 $bytes = [Text.Encoding]::ASCII.GetBytes($payload)
		$a_01_4 = {24 73 74 72 65 61 6d 2e 57 72 69 74 65 28 24 62 79 74 65 73 2c 20 30 2c 20 24 62 79 74 65 73 2e 4c 65 6e 67 74 68 29 } //1 $stream.Write($bytes, 0, $bytes.Length)
		$a_01_5 = {53 74 61 72 74 2d 53 6c 65 65 70 20 2d 53 65 63 6f 6e 64 73 20 34 } //1 Start-Sleep -Seconds 4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}