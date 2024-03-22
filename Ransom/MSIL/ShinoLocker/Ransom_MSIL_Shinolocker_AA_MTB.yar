
rule Ransom_MSIL_Shinolocker_AA_MTB{
	meta:
		description = "Ransom:MSIL/Shinolocker.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 69 6e 6f 4c 6f 63 6b 65 72 } //01 00  ShinoLocker
		$a_01_1 = {44 65 63 72 79 70 74 00 45 6e 63 72 79 70 74 00 43 6f 6e 76 65 72 74 } //01 00 
		$a_01_2 = {73 65 74 5f 42 6c 6f 63 6b 53 69 7a 65 00 73 65 74 5f 4b 65 79 53 69 7a 65 00 73 65 74 5f 50 61 64 64 69 6e 67 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  敳彴求捯卫穩e敳彴敋卹穩e敳彴慐摤湩g牆浯慂敳㐶瑓楲杮
	condition:
		any of ($a_*)
 
}