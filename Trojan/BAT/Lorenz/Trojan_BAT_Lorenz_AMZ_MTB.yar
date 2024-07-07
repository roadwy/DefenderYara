
rule Trojan_BAT_Lorenz_AMZ_MTB{
	meta:
		description = "Trojan:BAT/Lorenz.AMZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 93 fe 09 00 00 7b 14 00 00 04 fe 09 02 00 20 35 f3 78 38 20 61 00 48 ea 61 20 72 8b 58 dd 61 20 35 78 68 0f 59 65 5f 91 fe 09 02 00 60 61 d1 9d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}