
rule Trojan_Win32_AgentTesla_SG_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b9 50 f3 07 41 [0-06] 81 c1 f1 4d 39 00 [0-06] 83 c6 03 [0-06] 4e [0-02] 4e [0-04] ff 37 [0-04] 31 34 24 [0-04] 5b [0-04] 39 cb 75 } //1
		$a_02_1 = {bb 20 00 01 00 [0-0a] 83 eb 03 a9 6b eb 50 3f 83 eb 01 [0-06] ff 34 1f [0-0a] f7 c6 bf 3d 51 3f [0-06] 8f 04 18 [0-10] 31 34 18 [0-2a] 81 f9 ?? ?? ?? ?? [0-06] 7f } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}