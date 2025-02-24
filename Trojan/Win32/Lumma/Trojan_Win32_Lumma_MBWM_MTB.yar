
rule Trojan_Win32_Lumma_MBWM_MTB{
	meta:
		description = "Trojan:Win32/Lumma.MBWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f af d9 f7 d3 83 cb fe 83 fb ff 0f 94 c1 83 fa 0a 0f 9c c5 30 cd 0f 45 f0 83 fb ff 89 f1 0f 44 c8 } //2
		$a_01_1 = {0f af c8 89 c8 83 f0 fe 85 c8 0f 94 c3 83 fa 0a 0f 9c c7 30 df } //2
		$a_01_2 = {40 00 00 40 2e 64 61 74 61 00 00 00 7c 1b 00 00 00 80 04 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}