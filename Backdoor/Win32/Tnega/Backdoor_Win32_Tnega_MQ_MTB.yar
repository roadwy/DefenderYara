
rule Backdoor_Win32_Tnega_MQ_MTB{
	meta:
		description = "Backdoor:Win32/Tnega.MQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b5 0a c7 85 fc 34 4e ed 59 87 fe a0 ff cd 84 e2 80 77 79 a3 19 2f 78 f1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}