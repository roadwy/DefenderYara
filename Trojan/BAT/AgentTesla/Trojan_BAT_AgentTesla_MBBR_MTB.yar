
rule Trojan_BAT_AgentTesla_MBBR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {30 30 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d } //1 00=================================================
		$a_01_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //1 System.Reflection.Assembly
		$a_01_2 = {4b 00 50 00 2e 00 58 00 64 00 } //1 KP.Xd
		$a_01_3 = {33 36 30 66 38 34 64 37 33 66 30 33 } //1 360f84d73f03
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}