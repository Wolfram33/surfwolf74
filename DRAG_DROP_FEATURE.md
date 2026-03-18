# DRAG & DROP BOOKMARK FEATURE - Implementiert für Surfwolf74
# ================================================================

## Was wurde implementiert:

### 1. DraggableBookmarkButton Klasse
- Erbt von QToolButton
- Unterstützt Drag & Drop (Verschieben der Bookmarks)
- Visuelles Feedback beim Dragging (halbtransparente Darstellung)
- Automatische Navigation beim Klicken
- Rechtsklick-Kontextmenü (Umbenennen, Löschen)

### 2. Drag & Drop Features:
- **Drag Start**: Links-Mausklick gedrückt halten und bewegen
- **Visual Feedback**: Halbtransparente Darstellung während des Draggings
- **Drop Zones**: Links oder rechts von anderen Bookmarks
- **Auto-Reorder**: Automatische Neuanordnung in der bookmarks.json Datei

### 3. Enhanced Bookmark Management:
- Reihenfolge wird in bookmarks.json gespeichert
- `reorder_bookmarks()` Methode für persistente Speicherung
- Position detection (links/rechts vom Ziel-Button)

### 4. Styling:
- Bessere visuelle Darstellung der Bookmark-Buttons
- Hover-Effekte für bessere UX
- Border und Padding für professionellere Optik

## Bedienung:
1. **Bookmark verschieben**: Linke Maustaste auf Bookmark gedrückt halten und zu gewünschter Position ziehen
2. **Drop Position**: 
   - Links von einem Bookmark droppen = vor dem Bookmark einfügen
   - Rechts von einem Bookmark droppen = nach dem Bookmark einfügen
3. **Navigation**: Einfacher Klick auf Bookmark navigiert zur Website
4. **Kontextmenü**: Rechtsklick öffnet Menü zum Umbenennen/Löschen

## Technische Details:
- Verwendet PyQt6 Drag & Drop System (QDrag, QMimeData)
- MIME-Type: "bookmark:name:url" für Datenübertragung
- Persistente Speicherung in bookmarks.json mit Reihenfolge
- Event-Filter für Rechtsklick-Events bleibt erhalten
- Kompatibel mit vorhandenem Bookmark-Management-System

Die Implementierung ist vollständig in surfwolf74.py integriert!
