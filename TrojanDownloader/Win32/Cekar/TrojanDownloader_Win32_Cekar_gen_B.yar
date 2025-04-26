
rule TrojanDownloader_Win32_Cekar_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Cekar.gen!B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c9 89 4d f4 33 c9 89 4d f0 8b f8 4f 85 ff 7c 5b 47 33 c0 8b f0 8b ce c1 e1 02 03 ca 8b 09 03 4d fc 81 39 47 65 74 50 75 3e 8b d9 83 c3 04 81 3b 72 6f 63 41 75 31 8b d9 83 c3 08 81 3b 64 64 72 65 75 24 83 c1 0c 66 81 39 73 73 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}