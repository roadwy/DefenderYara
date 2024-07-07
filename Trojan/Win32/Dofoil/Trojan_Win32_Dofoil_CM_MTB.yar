
rule Trojan_Win32_Dofoil_CM_MTB{
	meta:
		description = "Trojan:Win32/Dofoil.CM!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 6c 89 45 68 8b 85 90 fe ff ff 01 45 68 8b 45 6c c1 e8 05 89 45 70 8b 45 70 33 7d 68 8b 8d 80 fe ff ff 03 c1 33 c7 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}