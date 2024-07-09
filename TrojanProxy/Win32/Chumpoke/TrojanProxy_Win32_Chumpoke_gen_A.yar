
rule TrojanProxy_Win32_Chumpoke_gen_A{
	meta:
		description = "TrojanProxy:Win32/Chumpoke.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 23 8d 95 74 ff ff ff b9 20 00 00 00 8b 45 fc e8 ?? ?? ff ff 83 f8 0a 0f 82 ?? 01 00 00 8b 85 74 ff ff ff 80 78 09 5d 75 2f 8d 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}