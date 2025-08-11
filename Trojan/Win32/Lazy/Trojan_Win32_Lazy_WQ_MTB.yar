
rule Trojan_Win32_Lazy_WQ_MTB{
	meta:
		description = "Trojan:Win32/Lazy.WQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 eb 3b e7 4f bb de d0 bf a0 bc a7 ef 57 ee 36 af 15 fa 3d cf 9d fe 42 bc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}