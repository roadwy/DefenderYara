
rule Trojan_BAT_AgentTesla_SPQP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {17 2d 06 d0 07 00 00 06 26 28 ?? ?? ?? 0a 72 97 00 00 70 6f ?? ?? ?? 0a 25 26 0b 73 1d 00 00 0a 0c } //2
		$a_01_1 = {42 00 74 00 6a 00 65 00 73 00 2e 00 70 00 6e 00 67 00 } //1 Btjes.png
		$a_81_2 = {70 75 62 6c 69 63 2e 63 6c 61 73 73 2e 4d 61 69 6e 2e 48 65 6c 6c 6f 57 6f 72 6c 64 2e 6d 6f 64 75 6c 65 32 } //1 public.class.Main.HelloWorld.module2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}