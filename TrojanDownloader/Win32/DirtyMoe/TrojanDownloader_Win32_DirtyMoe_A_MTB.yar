
rule TrojanDownloader_Win32_DirtyMoe_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/DirtyMoe.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 85 db 7e 90 01 01 8b 4d fc 8d 85 90 01 04 53 50 a1 90 01 04 03 c1 50 e8 83 01 00 00 01 5d fc 83 c4 90 01 01 81 7d fc 90 01 04 74 90 01 01 6a 00 8d 85 90 01 04 57 50 ff 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}