
rule TrojanDownloader_Win32_Deyma_SP_MTB{
	meta:
		description = "TrojanDownloader:Win32/Deyma.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 9c 81 c2 27 01 00 00 2b 55 f4 89 55 a8 8b 45 84 33 85 78 ff ff ff 89 45 84 81 7d e0 0c 01 00 00 77 09 } //2
		$a_01_1 = {8b 55 fc 83 c2 01 89 55 fc 83 7d fc 02 73 14 0f b7 45 bc 8b 4d e4 2b c8 81 c1 c0 00 00 00 89 4d cc eb dd } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}