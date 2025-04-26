
rule Trojan_Win32_CryptInject_CG_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 10 73 ?? 8b 4d fc 03 4d f4 8b 55 f8 03 55 f4 8a 02 88 01 eb } //8
		$a_81_1 = {72 65 64 20 6c 69 70 73 } //6 red lips
		$a_81_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*8+(#a_81_1  & 1)*6+(#a_81_2  & 1)*1) >=15
 
}