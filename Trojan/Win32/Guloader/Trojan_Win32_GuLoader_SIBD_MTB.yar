
rule Trojan_Win32_GuLoader_SIBD_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff d3 3d e5 [0-10] be ?? ?? ?? ?? [0-10] b9 ?? ?? ?? ?? [0-10] bf ?? ?? ?? ?? [0-10] 31 d2 [0-10] 33 14 0e [0-10] 09 14 08 [0-10] 31 3c 08 [0-10] 81 e9 ?? ?? ?? ?? [0-10] 81 c1 ?? ?? ?? ?? [0-10] 41 7d ?? [0-10] ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}