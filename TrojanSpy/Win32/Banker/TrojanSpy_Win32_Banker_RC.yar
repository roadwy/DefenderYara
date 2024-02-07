
rule TrojanSpy_Win32_Banker_RC{
	meta:
		description = "TrojanSpy:Win32/Banker.RC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6e 73 65 72 74 41 64 6a 61 63 65 6e 74 48 54 4d 4c } //02 00  insertAdjacentHTML
		$a_01_1 = {61 6c 69 70 61 79 2e 63 6f 6d 2f 65 62 61 6e 6b 2f 70 61 79 6d 65 6e 74 5f 67 61 74 65 77 61 79 2e 68 74 6d } //02 00  alipay.com/ebank/payment_gateway.htm
		$a_01_2 = {3c 69 6e 70 75 74 20 6e 61 6d 65 3d 22 62 61 6e 6b 49 44 22 20 74 79 70 65 3d 22 68 69 64 64 65 6e 22 20 76 61 6c 75 65 3d 22 } //01 00  <input name="bankID" type="hidden" value="
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d } //00 00  taskkill /f /im
	condition:
		any of ($a_*)
 
}