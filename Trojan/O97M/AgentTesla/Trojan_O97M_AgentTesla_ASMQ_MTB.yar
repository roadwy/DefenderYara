
rule Trojan_O97M_AgentTesla_ASMQ_MTB{
	meta:
		description = "Trojan:O97M/AgentTesla.ASMQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 7e 24 24 70 70 64 24 24 74 24 24 7e 7e 72 6f 24 24 6d 69 6e 67 7e 7e 6d 69 63 72 6f 73 6f 66 74 7e 7e 77 69 6e 64 6f 77 73 7e 7e 73 74 24 24 72 74 6d 65 6e 75 7e 7e 70 72 6f 67 72 24 24 6d 73 7e 7e 73 74 24 24 72 74 75 70 7e 7e 75 70 64 24 24 74 65 21 21 22 } //01 00  ~~$$ppd$$t$$~~ro$$ming~~microsoft~~windows~~st$$rtmenu~~progr$$ms~~st$$rtup~~upd$$te!!"
		$a_01_1 = {3a 3a 3a 3a 3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 22 7e 7e 22 2c 22 5c 5c 22 29 3a 3a 3a 3a 3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 22 21 21 22 2c 22 2e 6a 73 22 29 3a 3a 3a 3a 3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 22 24 24 22 2c 22 61 22 29 3d 22 40 40 7e 7e 75 73 65 72 73 7e 7e 70 75 62 6c 69 63 7e 7e 73 79 73 2e 69 6e 69 22 3a 3a 3a 3a 3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 22 7e 7e 22 2c 22 5c 22 29 3a 3a 3a 3a 3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 22 40 40 22 2c 22 63 3a 22 29 } //01 00  :::::=vba.replace(,"~~","\\"):::::=vba.replace(,"!!",".js"):::::=vba.replace(,"$$","a")="@@~~users~~public~~sys.ini":::::=vba.replace(,"~~","\"):::::=vba.replace(,"@@","c:")
		$a_01_2 = {40 40 2f 2f 62 2f 2f 65 3a 7e 7e 63 3a 26 75 73 65 72 73 26 70 75 62 6c 69 63 26 73 79 73 2e 69 6e 69 22 } //01 00  @@//b//e:~~c:&users&public&sys.ini"
		$a_01_3 = {3a 3a 3a 3a 3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 22 26 22 2c 22 5c 5c 22 29 3a 3a 3a 3a 3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 22 40 40 22 2c 22 77 73 63 72 69 70 74 2e 65 78 65 22 29 3a 3a 3a 3a 3a 3d 76 62 61 2e 72 65 70 6c 61 63 65 28 2c 22 7e 7e 22 2c 22 6a 73 63 72 69 70 74 22 29 64 65 62 75 67 2e 70 72 69 6e 74 3a 3a 3a 3a 3a 73 65 74 3d 67 65 74 6f 62 6a 65 63 74 28 22 6e 65 77 3a 7b 37 32 63 32 34 64 64 35 2d 64 37 30 61 2d 34 33 38 62 2d 38 61 34 32 2d 39 38 34 32 34 62 38 38 61 66 62 38 7d 22 29 64 65 62 75 67 2e 70 72 69 6e 74 3a 3a 3a 3a 3a 3a 3a 73 65 74 3d 5f 2e 5f 5f 65 78 65 63 21 28 29 64 65 62 75 67 2e 70 72 69 6e 74 65 6e 64 66 75 6e 63 74 69 6f 6e } //00 00  :::::=vba.replace(,"&","\\"):::::=vba.replace(,"@@","wscript.exe"):::::=vba.replace(,"~~","jscript")debug.print:::::set=getobject("new:{72c24dd5-d70a-438b-8a42-98424b88afb8}")debug.print:::::::set=_.__exec!()debug.printendfunction
	condition:
		any of ($a_*)
 
}