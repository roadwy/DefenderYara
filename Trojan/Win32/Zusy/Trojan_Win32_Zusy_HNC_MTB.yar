
rule Trojan_Win32_Zusy_HNC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.HNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {9c 60 55 8b ec 48 58 53 4f 5f 4f 3f b8 02 00 00 01 61 9d } //2
		$a_01_1 = {60 55 8b ec 53 33 db 57 68 01 80 00 00 53 6a 08 53 68 60 01 00 00 50 53 68 80 ec 41 00 68 80 91 40 00 68 c0 2e 42 00 50 53 81 c4 38 00 00 00 c9 61 9d } //1
		$a_01_2 = {68 01 80 00 00 25 ff ff ff bf 66 3d 06 00 81 c4 0c 00 00 00 c9 61 9d } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=3
 
}