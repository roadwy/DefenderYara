
rule TrojanSpy_Win32_Banker_WH{
	meta:
		description = "TrojanSpy:Win32/Banker.WH,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 45 6e 74 65 72 5d } //1 [Enter]
		$a_01_1 = {5b 53 70 61 63 65 5d } //1 [Space]
		$a_00_2 = {43 61 70 74 69 6f 6e 3a } //1 Caption:
		$a_00_3 = {7e 6c 6f 67 2e 74 6d 70 } //1 ~log.tmp
		$a_00_4 = {2f 6c 6f 67 73 2f 67 61 74 65 2e 70 68 70 } //1 /logs/gate.php
		$a_00_5 = {62 61 6e 6b 73 2d 6d 6f 6e 65 79 2e 63 6f 6d } //1 banks-money.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}