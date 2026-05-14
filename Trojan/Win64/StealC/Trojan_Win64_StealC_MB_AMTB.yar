
rule Trojan_Win64_StealC_MB_AMTB{
	meta:
		description = "Trojan:Win64/StealC.MB!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {67 65 6e 73 65 72 76 33 33 33 2e 74 6f 70 } //genserv333.top  2
		$a_80_1 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 20 43 6c 69 65 6e 74 2f 31 2e 30 } //Notification Client/1.0  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}