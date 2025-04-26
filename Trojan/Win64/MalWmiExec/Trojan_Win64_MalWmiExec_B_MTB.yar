
rule Trojan_Win64_MalWmiExec_B_MTB{
	meta:
		description = "Trojan:Win64/MalWmiExec.B!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 10 4c 24 40 0f 11 4d 98 0f 10 45 b8 0f 11 45 a8 48 8d 55 98 66 48 0f 7e c8 48 83 fb 0f 48 0f 47 d0 33 db 48 89 5c 24 20 4c 8d 4c 24 70 66 41 0f 7e c0 49 8b cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}