
rule Trojan_Win32_Yolox_A_MTB{
	meta:
		description = "Trojan:Win32/Yolox.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 03 c0 40 32 cb 0f b6 d0 33 c0 40 f6 d1 80 d9 90 01 01 0f c0 c2 0f ba fa 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}