
rule Trojan_Win32_AgentTesla_FE_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 f9 00 7f 90 0a 75 00 68 e0 5e 00 00 [0-10] 59 [0-10] 83 e9 04 [0-10] 8b 1c 0f [0-20] 31 f3 [0-25] 09 1c 08 [0-15] 83 f9 00 7f } //1
		$a_02_1 = {68 e0 5e 00 00 90 0a 75 00 b9 ?? ?? ?? 41 [0-10] 81 c1 ?? ?? ?? ?? [0-10] 83 c6 02 [0-10] 4e [0-10] 8b 1f [0-10] 31 f3 [0-10] 39 cb 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}