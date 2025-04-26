
rule Trojan_Win32_NSISInject_SPGJ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SPGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {70 6c 65 62 65 69 61 6e 69 73 69 6e 67 5c 6f 72 6f 67 72 61 70 68 69 63 61 6c 6c 79 2e 53 61 70 } //1 plebeianising\orographically.Sap
		$a_01_1 = {73 74 65 72 73 73 74 72 61 6e 64 65 5c 61 70 6f 70 6c 65 6b 74 69 6b 65 72 5c 68 75 6d 6f 72 6c 65 73 73 6e 65 73 73 65 73 } //1 stersstrande\apoplektiker\humorlessnesses
		$a_01_2 = {6e 61 62 6f 62 65 62 6f 65 6c 73 65 6e 73 5c 48 75 6c 64 61 68 5c 74 73 61 64 65 2e 69 6e 69 } //1 nabobeboelsens\Huldah\tsade.ini
		$a_01_3 = {73 61 6d 6d 65 6e 73 74 69 6c 6c 69 6e 67 65 72 6e 65 73 5c 6b 72 72 65 2e 73 6b 6f } //1 sammenstillingernes\krre.sko
		$a_01_4 = {66 6c 61 67 73 70 74 74 65 72 6e 65 73 5c 73 74 6f 72 62 6f 72 67 65 72 5c 75 6e 73 74 61 76 61 62 6c 65 5c 73 74 65 61 64 69 65 73 74 2e 69 6e 69 } //1 flagsptternes\storborger\unstavable\steadiest.ini
		$a_01_5 = {54 65 6c 65 66 6f 6e 73 74 6f 72 6d 65 5c 73 74 61 74 69 73 74 69 6b 70 72 6f 67 72 61 6d 6d 65 72 73 5c 66 75 6c 64 62 6c 6f 64 73 68 65 73 74 65 73 2e 66 6f 72 } //1 Telefonstorme\statistikprogrammers\fuldblodshestes.for
		$a_01_6 = {54 68 6f 72 6e 69 33 38 5c 48 61 75 6c 61 67 65 73 2e 75 64 74 } //1 Thorni38\Haulages.udt
		$a_01_7 = {52 65 63 75 6d 62 65 6e 63 79 32 31 37 2e 6b 6f 61 } //1 Recumbency217.koa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}