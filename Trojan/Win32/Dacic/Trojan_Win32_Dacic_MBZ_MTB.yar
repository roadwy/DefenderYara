
rule Trojan_Win32_Dacic_MBZ_MTB{
	meta:
		description = "Trojan:Win32/Dacic.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 3b 40 00 b0 18 40 00 7f f2 30 01 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 01 00 e9 00 00 00 50 14 40 00 90 16 40 00 e8 11 40 00 78 00 00 00 83 00 00 00 8c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}