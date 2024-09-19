
rule TrojanDownloader_Win32_Scar_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Scar.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 84 2a d4 54 40 00 8b fe 34 01 83 c9 ff 88 82 d4 54 40 00 33 c0 42 f2 ae f7 d1 49 3b d1 72 e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}