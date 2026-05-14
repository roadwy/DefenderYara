
rule Trojan_BAT_AsyncRAT_SXB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 61 76 65 20 70 61 79 6c 6f 61 64 20 74 6f 20 2e 63 6f 6e 66 69 67 20 66 6f 6c 64 65 72 } //20 Save payload to .config folder
		$a_01_1 = {5b 53 79 73 74 65 6d 2e 49 4f 2e 46 69 6c 65 5d 3a 3a 57 72 69 74 65 41 6c 6c 42 79 74 65 73 28 24 65 78 65 63 50 61 74 68 2c 20 24 64 65 63 72 79 70 74 65 64 42 79 74 65 73 29 } //10 [System.IO.File]::WriteAllBytes($execPath, $decryptedBytes)
		$a_01_2 = {4e 65 77 2d 49 74 65 6d 20 2d 50 61 74 68 20 24 65 78 65 63 44 69 72 20 2d 49 74 65 6d 54 79 70 65 20 44 69 72 65 63 74 6f 72 79 20 3e 20 24 6e 75 6c 6c } //5 New-Item -Path $execDir -ItemType Directory > $null
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}