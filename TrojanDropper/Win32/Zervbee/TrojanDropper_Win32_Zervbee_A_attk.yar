
rule TrojanDropper_Win32_Zervbee_A_attk{
	meta:
		description = "TrojanDropper:Win32/Zervbee.A!attk,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 00 2e 00 24 00 61 00 2e 00 6c 00 65 00 6e 00 67 00 74 00 68 00 5d 00 3b 00 5b 00 69 00 6f 00 2e 00 66 00 69 00 6c 00 65 00 5d 00 3a 00 3a 00 57 00 72 00 69 00 74 00 65 00 41 00 6c 00 6c 00 62 00 79 00 74 00 65 00 73 00 28 00 24 00 74 00 2b 00 27 00 5c 00 2e 00 76 00 62 00 65 00 27 00 2c 00 24 00 71 00 29 00 3b 00 43 00 73 00 43 00 72 00 49 00 70 00 54 00 20 00 24 00 74 00 27 00 5c 00 2e 00 76 00 62 00 65 00 27 00 } //00 00  ..$a.length];[io.file]::WriteAllbytes($t+'\.vbe',$q);CsCrIpT $t'\.vbe'
	condition:
		any of ($a_*)
 
}