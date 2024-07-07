
rule TrojanDownloader_BAT_Tiny_HJKL_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.HJKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f } //1 https://transfer.sh/get/
		$a_81_1 = {2f 6b 20 53 54 41 52 54 } //1 /k START
		$a_81_2 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_81_3 = {53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e } //1 Set-MpPreference -ExclusionExtension
		$a_81_4 = {53 74 61 72 74 2d 53 6c 65 65 70 20 2d 73 } //1 Start-Sleep -s
		$a_81_5 = {63 75 72 6c 2e 65 78 65 20 2d 6f } //1 curl.exe -o
		$a_81_6 = {2d 2d 75 72 6c } //1 --url
		$a_81_7 = {45 78 70 6c 6f 69 74 } //1 Exploit
		$a_81_8 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_81_9 = {26 20 45 58 49 54 } //1 & EXIT
		$a_81_10 = {47 65 74 48 61 73 68 43 6f 64 65 } //1 GetHashCode
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}