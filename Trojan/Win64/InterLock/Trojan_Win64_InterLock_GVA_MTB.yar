
rule Trojan_Win64_InterLock_GVA_MTB{
	meta:
		description = "Trojan:Win64/InterLock.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 48 89 e5 48 83 ec 40 48 89 75 f8 48 89 f1 48 81 c1 ?? ?? ?? 00 e8 ?? ?? ?? ?? 48 89 c6 48 89 05 ?? ?? ?? ?? e8 05 00 00 00 90 13 48 8b 07 48 89 45 f0 48 83 c7 08 48 31 db 0f 31 48 89 55 e0 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}