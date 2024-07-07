
rule Trojan_Win32_Redline_GPAI_MTB{
	meta:
		description = "Trojan:Win32/Redline.GPAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 45 fc 33 55 fc 81 3d } //2
		$a_01_1 = {62 65 78 6f 6d 69 6e 61 79 75 6e 61 63 69 79 69 68 6f 67 75 63 75 74 65 6a 65 66 69 66 } //2 bexominayunaciyihogucutejefif
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}