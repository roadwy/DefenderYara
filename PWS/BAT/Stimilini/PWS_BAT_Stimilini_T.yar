
rule PWS_BAT_Stimilini_T{
	meta:
		description = "PWS:BAT/Stimilini.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6d 2e 46 6f 72 6d 73 2e 46 61 6b 65 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 00 } //1
		$a_01_1 = {53 74 65 61 6d 2e 65 78 65 00 53 74 65 61 6d 00 } //1
		$a_01_2 = {46 61 6b 65 46 6f 72 6d 00 53 74 65 61 6d 2e 46 6f 72 6d 73 00 46 6f 72 6d 00 } //1 慆敫潆浲匀整浡䘮牯獭䘀牯m
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}