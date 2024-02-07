
rule TrojanSpy_AndroidOS_SmsThief_O{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.O,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 74 61 72 74 53 65 6e 64 4c 6f 63 61 6c } //01 00  startSendLocal
		$a_00_1 = {41 78 51 50 43 7a 49 42 41 43 67 58 4c 51 49 52 41 78 34 43 42 41 51 59 55 31 64 4f } //01 00  AxQPCzIBACgXLQIRAx4CBAQYU1dO
		$a_00_2 = {41 77 45 2b 44 41 34 43 48 51 38 4e 44 6a 67 47 41 68 30 3d } //00 00  AwE+DA4CHQ8NDjgGAh0=
	condition:
		any of ($a_*)
 
}