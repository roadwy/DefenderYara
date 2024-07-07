
rule Trojan_BAT_Lokibot_SST1_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.SST1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 } //1 powershell Start-Process -FilePath
		$a_81_2 = {25 54 65 6d 70 25 } //1 %Temp%
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_5 = {2f 63 20 70 6f 77 65 72 73 68 65 6c 6c } //1 /c powershell
		$a_81_6 = {65 63 36 33 32 66 64 39 2d 31 36 39 34 2d 34 66 34 61 2d 39 62 66 66 2d 66 32 30 36 30 30 65 33 37 39 38 31 } //1 ec632fd9-1694-4f4a-9bff-f20600e37981
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}