
rule Trojan_Win64_Convagent_RC_MTB{
	meta:
		description = "Trojan:Win64/Convagent.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 88 db 80 f3 ff 80 e3 01 40 b6 01 40 88 f7 40 80 f7 01 45 88 de 41 20 fe 44 08 f3 40 88 f7 } //5
		$a_01_1 = {6f 75 74 2e 64 6c 6c 00 78 00 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}