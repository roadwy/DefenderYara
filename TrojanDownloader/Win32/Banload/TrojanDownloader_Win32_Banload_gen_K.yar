
rule TrojanDownloader_Win32_Banload_gen_K{
	meta:
		description = "TrojanDownloader:Win32/Banload.gen!K,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {7d 03 47 eb 05 bf 01 00 00 00 a1 ?? ?? ?? ?? 33 db 8a 5c 38 ff 33 5d e8 3b 5d f0 7f 0b 81 c3 ff 00 00 00 2b 5d f0 eb 03 } //2
		$a_01_1 = {6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a 00 6a 00 e8 } //1
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}