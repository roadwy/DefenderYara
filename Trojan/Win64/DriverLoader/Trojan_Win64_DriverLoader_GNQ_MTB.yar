
rule Trojan_Win64_DriverLoader_GNQ_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 dd 03 44 ?? ?? 08 dd 03 44 38 ?? 18 dd 03 44 68 ?? d0 dd 03 44 50 ?? c0 dd ?? 44 c0 45 ?? ?? 52 6c 8d a3 } //10
		$a_03_1 = {43 31 3f 6c 2b a2 ?? ?? ?? ?? 52 0b eb d3 2f 86 f6 dc 6c 5c } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}