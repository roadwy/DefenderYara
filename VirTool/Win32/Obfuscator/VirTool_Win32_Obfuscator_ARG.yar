
rule VirTool_Win32_Obfuscator_ARG{
	meta:
		description = "VirTool:Win32/Obfuscator.ARG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4b 3a 5c 62 43 49 6e 58 55 63 6f 69 45 48 5c 65 4f 62 76 41 6d 64 54 69 50 77 73 5c 62 68 79 34 37 78 00 64 44 42 58 7a 47 79 73 74 73 00 5a 56 } //1 㩋扜䥃塮捕楯䡅敜扏䅶摭楔睐屳桢㑹砷搀䉄穘祇瑳s噚
	condition:
		((#a_01_0  & 1)*1) >=1
 
}