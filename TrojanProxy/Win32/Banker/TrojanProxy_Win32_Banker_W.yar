
rule TrojanProxy_Win32_Banker_W{
	meta:
		description = "TrojanProxy:Win32/Banker.W,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {94 ee 83 bd c0 8f b6 02 bf d5 6e fd cc b0 39 5d c8 f8 f6 b7 46 d0 5b c7 aa ce 3d 04 d6 a9 5c 8f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}