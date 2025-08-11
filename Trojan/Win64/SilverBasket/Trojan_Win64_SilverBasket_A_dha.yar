
rule Trojan_Win64_SilverBasket_A_dha{
	meta:
		description = "Trojan:Win64/SilverBasket.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 53 6b 79 50 44 46 5c 43 6c 73 53 72 76 2e 69 6e 66 } //C:\ProgramData\SkyPDF\ClsSrv.inf  1
		$a_80_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 53 6b 79 50 44 46 5c 50 44 55 44 72 76 2e 62 6c 66 } //C:\ProgramData\SkyPDF\PDUDrv.blf  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}