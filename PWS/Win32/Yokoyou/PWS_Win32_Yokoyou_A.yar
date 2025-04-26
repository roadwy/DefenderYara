
rule PWS_Win32_Yokoyou_A{
	meta:
		description = "PWS:Win32/Yokoyou.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b d0 8a 83 ?? ?? ?? ?? 32 d0 8d 45 f4 e8 ?? ?? ff ff 8b 55 f4 8b c7 e8 ?? ?? ff ff 43 81 e3 07 00 00 80 79 05 4b 83 cb f8 43 ff 45 f8 4e 75 a1 } //2
		$a_01_1 = {43 5a 64 6c 6c 2e 64 6c 6c 00 53 74 61 72 74 48 6f 6f 6b 00 53 74 6f 70 48 6f 6f 6b 00 70 74 5f 6b 73 48 6f 6f 6b 00 70 74 5f 74 7a 48 6f 6f 6b } //1
		$a_01_2 = {41 74 78 74 5f 4e 61 6d 65 69 70 74 3d 00 } //1 瑁瑸也浡楥瑰=
		$a_01_3 = {41 74 78 74 50 61 73 73 77 6f 72 64 3d 00 } //1 瑁瑸慐獳潷摲=
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}