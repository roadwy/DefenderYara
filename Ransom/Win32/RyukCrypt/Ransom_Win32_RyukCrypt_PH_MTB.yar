
rule Ransom_Win32_RyukCrypt_PH_MTB{
	meta:
		description = "Ransom:Win32/RyukCrypt.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 00 6e 00 63 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  EncReadMe.html
		$a_01_1 = {2e 00 65 00 6e 00 63 00 } //01 00  .enc
		$a_01_2 = {6e 65 74 20 73 74 6f 70 20 41 6e 74 69 76 69 72 75 73 } //01 00  net stop Antivirus
		$a_01_3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 20 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 20 00 61 00 6c 00 6c 00 20 00 2f 00 20 00 71 00 75 00 69 00 65 00 74 00 } //00 00  cmd.exe / c vssadmin delete shadows / all / quiet
	condition:
		any of ($a_*)
 
}