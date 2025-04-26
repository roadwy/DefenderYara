
rule Trojan_Win32_Virlock_NV_MTB{
	meta:
		description = "Trojan:Win32/Virlock.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {e9 cb e3 ff ff ff d1 43 c1 c6 ?? 33 f7 8b d6 e9 fe 02 00 00 68 ?? ?? ?? ?? c1 e7 1a 03 da 87 f7 81 c2 ?? ?? ?? ?? 03 f7 03 df } //2
		$a_03_1 = {8b fe 33 df 47 2b fb 81 ca ?? ?? ?? ?? f7 da 2b d6 81 f2 ?? ?? ?? ?? c1 ef 10 c1 ca ?? c1 ee 14 e9 6c 01 00 00 } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}