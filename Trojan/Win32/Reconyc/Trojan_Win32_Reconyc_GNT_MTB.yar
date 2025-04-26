
rule Trojan_Win32_Reconyc_GNT_MTB{
	meta:
		description = "Trojan:Win32/Reconyc.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff 34 1a 40 00 c0 54 40 00 10 93 40 00 10 } //10
		$a_01_1 = {5c 67 75 6f 64 6f 6e 67 67 75 6f 64 6f 6e 67 2e 67 75 6f 64 6f 6e 67 } //1 \guodongguodong.guodong
		$a_01_2 = {5c 73 76 63 68 65 73 74 2e 65 78 65 } //1 \svchest.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}