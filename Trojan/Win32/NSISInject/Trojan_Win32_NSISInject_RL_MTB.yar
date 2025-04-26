
rule Trojan_Win32_NSISInject_RL_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f0 03 55 fc 0f b6 02 33 c1 8b 4d f0 03 4d fc 88 01 8b 55 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}