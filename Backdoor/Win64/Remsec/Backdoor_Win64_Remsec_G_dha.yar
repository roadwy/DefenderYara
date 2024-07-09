
rule Backdoor_Win64_Remsec_G_dha{
	meta:
		description = "Backdoor:Win64/Remsec.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 55 8b ec be ?? ?? ?? ?? 50 ad 8b c8 ad ff e1 c9 5e ff e0 ff 20 8b f0 eb ef 8f 00 8b 00 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}