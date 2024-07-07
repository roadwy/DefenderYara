
rule Trojan_Win32_FlyStudio_K{
	meta:
		description = "Trojan:Win32/FlyStudio.K,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 25 25 00 62 6f 64 79 00 69 6e 6e 65 72 48 54 4d 4c 00 6e 47 3a 35 5f 6c 6e 3d 3d 32 6d 43 32 } //1 ╁%潢祤椀湮牥呈䱍渀㩇張湬㴽洲㉃
		$a_01_1 = {27 7b 27 00 47 30 30 47 4c 45 00 69 78 65 78 57 } //1 笧'ぇ䜰䕌椀數坸
		$a_01_2 = {4e 65 77 53 6f 63 6b 00 53 6f 66 74 77 61 72 65 5c 46 6c 79 53 6b 79 5c 45 5c 49 6e 73 74 61 6c } //1 敎卷捯k潓瑦慷敲䙜祬歓屹居湉瑳污
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}