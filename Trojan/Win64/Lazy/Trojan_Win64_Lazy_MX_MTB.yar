
rule Trojan_Win64_Lazy_MX_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MX!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 20 2f 6d 69 6e 20 63 6d 64 2e 65 78 65 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e } //1 start /min cmd.exe /c powershell -WindowStyle Hidden
		$a_01_1 = {7a 65 74 6f 6c 61 63 73 2d 63 6c 6f 75 64 2e 74 6f 70 } //5 zetolacs-cloud.top
		$a_01_2 = {74 65 78 74 70 75 62 73 68 69 65 72 73 2e 74 6f 70 } //5 textpubshiers.top
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=11
 
}