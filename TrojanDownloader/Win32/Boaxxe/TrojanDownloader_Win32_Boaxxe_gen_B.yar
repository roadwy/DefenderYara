
rule TrojanDownloader_Win32_Boaxxe_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Boaxxe.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 49 4d 47 5f 30 25 34 21 64 21 2e 6a 70 67 } //1 /IMG_0%4!d!.jpg
		$a_01_1 = {21 64 21 2e 6a 70 67 00 00 00 00 69 00 00 00 77 00 00 00 25 31 21 73 21 25 32 21 73 21 6e 69 6e 65 74 2e 64 6c 6c } //1
		$a_03_2 = {3d 25 31 21 64 21 2d 00 90 09 0c 00 52 61 6e 67 65 3a 20 62 79 74 65 73 } //2
		$a_00_3 = {3b f0 7e e8 6a 7b 58 66 89 85 00 fe ff ff } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_00_3  & 1)*2) >=5
 
}