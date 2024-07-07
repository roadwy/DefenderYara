
rule Trojan_Win32_Startpage_RL{
	meta:
		description = "Trojan:Win32/Startpage.RL,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {b2 e9 c9 b1 b2 a1 b6 be 2e 75 72 6c } //2
		$a_01_1 = {77 77 77 2e 67 6f 32 30 30 30 2e 63 6e 2f 3f 31 } //1 www.go2000.cn/?1
		$a_01_2 = {77 77 77 2e 6c 65 69 6c 65 69 6b 75 61 69 2e 63 6e 2f 77 65 6c 63 6f 6d 65 2e 70 68 70 3f 74 6e 3d } //1 www.leileikuai.cn/welcome.php?tn=
		$a_01_3 = {fe 02 17 5c c6 f4 b6 af 5c cc da d1 b6 51 51 2e 6c 6e 6b } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}