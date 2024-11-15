
rule Trojan_Win32_LummaStealer_VG_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.VG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 a5 8b 74 24 f8 8b 7c 24 f4 8d 54 24 04 ff 54 24 fc c3 } //2
		$a_01_1 = {51 6b 6b 62 61 6c } //1 Qkkbal
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}