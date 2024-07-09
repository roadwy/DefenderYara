
rule Trojan_Win32_Agent_DSK_MTB{
	meta:
		description = "Trojan:Win32/Agent.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 8d f4 f7 ff ff 0f 44 c1 80 e2 c0 08 95 fa f7 ff ff a3 ?? ?? ?? ?? 81 f3 50 d0 a8 64 81 ad f4 f7 ff ff e6 23 75 66 c1 e0 04 81 85 f4 f7 ff ff 44 4f ea 10 81 85 f4 f7 ff ff a6 d4 8a 55 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}