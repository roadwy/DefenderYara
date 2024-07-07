
rule TrojanSpy_Win32_Ursnif_gen_D{
	meta:
		description = "TrojanSpy:Win32/Ursnif.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 e8 85 ff ff ff 8b 4d 0c 83 e9 04 03 4d 08 39 01 75 90 01 01 8b 55 08 ff 32 8f 45 fc 8b 45 fc 83 c0 10 50 6a 40 8d 87 90 01 01 02 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}